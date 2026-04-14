---
name: gha-security-review
description: Find exploitable vulnerabilities in GitHub Actions workflows. Every finding MUST include a concrete exploitation scenario — if you can't build the attack, don't report it. 
category: Security & Systems
source: antigravity
tags: [markdown, claude, ai, agent, workflow, security, vulnerability]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/gha-security-review
---


<!--
Attack patterns and real-world examples sourced from the HackerBot Claw campaign analysis
by StepSecurity (2025): https://www.stepsecurity.io/blog/hackerbot-claw-github-actions-exploitation
-->

# GitHub Actions Security Review

Find exploitable vulnerabilities in GitHub Actions workflows. Every finding MUST include a concrete exploitation scenario — if you can't build the attack, don't report it.

This skill encodes attack patterns from real GitHub Actions exploits — not generic CI/CD theory.

## When to Use
- You are reviewing GitHub Actions workflows for exploitable security issues.
- The task requires tracing a concrete attack path from an external attacker to workflow execution or secret exposure.
- You need a security review of workflow files, composite actions, or workflow-related scripts with evidence-based findings only.

## Scope

Review the workflows provided (file, diff, or repo). Research the codebase as needed to trace complete attack paths before reporting.

### Files to Review

- `.github/workflows/*.yml` — all workflow definitions
- `action.yml` / `action.yaml` — composite actions in the repo
- `.github/actions/*/action.yml` — local reusable actions
- Config files loaded by workflows: `CLAUDE.md`, `AGENTS.md`, `Makefile`, shell scripts under `.github/`

### Out of Scope

- Workflows in other repositories (only note the dependency)
- GitHub App installation permissions (note if relevant)

## Threat Model

Only report vulnerabilities exploitable by an **external attacker** — someone **without** write access to the repository. The attacker can open PRs from forks, create issues, and post comments. They cannot push to branches, trigger `workflow_dispatch`, or trigger manual workflows.

**Do not flag** vulnerabilities that require write access to exploit:
- `workflow_dispatch` input injection — requires write access to trigger
- Expression injection in `push`-only workflows on protected branches
- `workflow_call` input injection where all callers are internal
- Secrets in `workflow_dispatch`/`schedule`-only workflows

## Confidence

Report only **HIGH** and **MEDIUM** confidence findings. Do not report theoretical issues.

| Confidence | Criteria | Action |
|---|---|---|
| **HIGH** | Traced the full attack path, confirmed exploitable | Report with exploitation scenario and fix |
| **MEDIUM** | Attack path partially confirmed, uncertain link | Report as needs verification |
| **LOW** | Theoretical or mitigated elsewhere | Do not report |

For each HIGH finding, provide all five elements:

1. **Entry point** — How does the attacker get in? (fork PR, issue comment, branch name, etc.)
2. **Payload** — What does the attacker send? (actual code/YAML/input)
3. **Execution mechanism** — How does the payload run? (expression expansion, checkout + script, etc.)
4. **Impact** — What does the attacker gain? (token theft, code execution, repo write access)
5. **PoC sketch** — Concrete steps an attacker would follow

If you cannot construct all five, report as MEDIUM (needs verification).

---

## Step 1: Classify Triggers and Load References

For each workflow, identify triggers and load the appropriate reference:

| Trigger / Pattern | Load Reference |
|---|---|
| `pull_request_target` | `references/pwn-request.md` |
| `issue_comment` with command parsing | `references/comment-triggered-commands.md` |
| `${{ }}` in `run:` blocks | `references/expression-injection.md` |
| PATs / deploy keys / elevated credentials | `references/credential-escalation.md` |
| Checkout PR code + config file loading | `references/ai-prompt-injection-via-ci.md` |
| Third-party actions (especially unpinned) | `references/supply-chain.md` |
| `permissions:` block or secrets usage | `references/permissions-and-secrets.md` |
| Self-hosted runners, cache/artifact usage | `references/runner-infrastructure.md` |
| Any confirmed finding | `references/real-world-attacks.md` |

Load references selectively — only what's relevant to the triggers found.

## Step 2: Check for Vulnerability Classes

### Check 1: Pwn Request

Does the workflow use `pull_request_target` AND check out fork code?
- Look for `actions/checkout` with `ref:` pointing to PR head
- Look for local actions (`./.github/actions/`) that would come from the fork
- Check if any `run:` step executes code from the checked-out PR

### Check 2: Expression Injection

Are `${{ }}` expressions used inside `run:` blocks in externally-triggerable workflows?
- Map every `${{ }}` expression in every `run:` step
- Confirm the value is attacker-controlled (PR title, branch name, comment body — not numeric IDs, SHAs, or repository names)
- Confirm the expression is in a `run:` block, not `if:`, `with:`, or job-level `env:`

### Check 3: Unauthorized Command Execution

Does an `issue_comment`-triggered workflow execute commands without authorization?
- Is there an `author_association` check?
- Can any GitHub user trigger the command?
- Does the command handler also use injectable express
