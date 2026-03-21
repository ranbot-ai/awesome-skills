---
name: agentic-actions-auditor
description: Audits GitHub Actions workflows for security vulnerabilities in AI agent integrations  including Claude Code Action,  Gemini CLI, OpenAI Codex, and GitHub AI  Inference.  Detects attack vectors where 
category: AI & Agents
source: antigravity
tags: [python, node, api, claude, ai, agent, workflow, document, security, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/agentic-actions-auditor
---


# Agentic Actions Auditor

Static security analysis guidance for GitHub Actions workflows that invoke AI coding agents. This skill teaches you how to discover workflow files locally or from remote GitHub repositories, identify AI action steps, follow cross-file references to composite actions and reusable workflows that may contain hidden AI agents, capture security-relevant configuration, and detect attack vectors where attacker-controlled input reaches an AI agent running in a CI/CD pipeline.

## When to Use
- Auditing a repository's GitHub Actions workflows for AI agent security
- Reviewing CI/CD configurations that invoke Claude Code Action, Gemini CLI, or OpenAI Codex
- Checking whether attacker-controlled input can reach AI agent prompts
- Evaluating agentic action configurations (sandbox settings, tool permissions, user allowlists)
- Assessing trigger events that expose workflows to external input (`pull_request_target`, `issue_comment`, etc.)
- Investigating data flow from GitHub event context through `env:` blocks to AI prompt fields

## When NOT to Use

- Analyzing workflows that do NOT use any AI agent actions (use general Actions security tools instead)
- Reviewing standalone composite actions or reusable workflows outside of a caller workflow context (use this skill when analyzing a workflow that references them via `uses:`)
- Performing runtime prompt injection testing (this is static analysis guidance, not exploitation)
- Auditing non-GitHub CI/CD systems (Jenkins, GitLab CI, CircleCI)
- Auto-fixing or modifying workflow files (this skill reports findings, does not modify files)

## Rationalizations to Reject

When auditing agentic actions, reject these common rationalizations. Each represents a reasoning shortcut that leads to missed findings.

**1. "It only runs on PRs from maintainers"**
Wrong because it ignores `pull_request_target`, `issue_comment`, and other trigger events that expose actions to external input. Attackers do not need write access to trigger these workflows. A `pull_request_target` event runs in the context of the base branch, not the PR branch, meaning any external contributor can trigger it by opening a PR.

**2. "We use allowed_tools to restrict what it can do"**
Wrong because tool restrictions can still be weaponized. Even restricted tools like `echo` can be abused for data exfiltration via subshell expansion (`echo $(env)`). A tool allowlist reduces attack surface but does not eliminate it. Limited tools != safe tools.

**3. "There's no ${{ }} in the prompt, so it's safe"**
Wrong because this is the classic env var intermediary miss. Data flows through `env:` blocks to the prompt field with zero visible expressions in the prompt itself. The YAML looks clean but the AI agent still receives attacker-controlled input. This is the most commonly missed vector because reviewers only look for direct expression injection.

**4. "The sandbox prevents any real damage"**
Wrong because sandbox misconfigurations (`danger-full-access`, `Bash(*)`, `--yolo`) disable protections entirely. Even properly configured sandboxes leak secrets if the AI agent can read environment variables or mounted files. The sandbox boundary is only as strong as its configuration.

## Audit Methodology

Follow these steps in order. Each step builds on the previous one.

### Step 0: Determine Analysis Mode

If the user provides a GitHub repository URL or `owner/repo` identifier, use remote analysis mode. Otherwise, use local analysis mode (proceed to Step 1).

#### URL Parsing

Extract `owner/repo` and optional `ref` from the user's input:

| Input Format | Extract |
|-------------|---------|
| `owner/repo` | owner, repo; ref = default branch |
| `owner/repo@ref` | owner, repo, ref (branch, tag, or SHA) |
| `https://github.com/owner/repo` | owner, repo; ref = default branch |
| `https://github.com/owner/repo/tree/main/...` | owner, repo; strip extra path segments |
| `github.com/owner/repo/pull/123` | Suggest: "Did you mean to analyze owner/repo?" |

Strip trailing slashes, `.git` suffix, and `www.` prefix. Handle both `http://` and `https://`.

#### Fetch Workflow Files

Use a two-step approach with `gh api`:

1. **List workflow directory:**
   ```
   gh api repos/{owner}/{repo}/contents/.github/workflows --paginate --jq '.[].name'
   ```
   If a ref is specified, append `?ref={ref}` to the URL.

2. **Filter for YAML files:** Keep only filenames ending in `.yml` or `.yaml`.

3. **Fetch each file's content:**
   ```
   gh api repos/{owner}/{repo}/contents/.github/workflows/{filename} --jq '.content | @base64d'
   ```
   If a ref is specified, append `?ref={ref}` to this URL too. The ref must be included on EVERY API call, not just the directory listing.

4. Report: "Found N workflow files in owner/repo: file1.yml, file2.yml, ..."
5. Proceed to Step 2 with the fetched YAML content.

#### Error Handling

Do NOT pre-check `gh auth status` before API calls. Attempt the API call and handle failures:

- **401/a
