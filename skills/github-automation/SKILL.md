---
name: github-automation
description: Automate GitHub repositories, issues, pull requests, branches, CI/CD, and permissions via Rube MCP (Composio). Manage code workflows, review PRs, search code, and handle deployments programmatically. 
category: Development & Code Tools
source: composio
tags: [python, api, git, github, markdown, json, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/github-automation
---


# GitHub Automation via Rube MCP

Automate GitHub repository management, issue tracking, pull request workflows, branch operations, and CI/CD through Composio's GitHub toolkit.

**Toolkit docs**: [composio.dev/toolkits/github](https://composio.dev/toolkits/github)

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active GitHub connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `github`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `github`
3. If connection is not ACTIVE, follow the returned auth link to complete GitHub OAuth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Create and Manage Issues

**When to use**: User wants to create, list, or manage GitHub issues

**Tool sequence**:
1. `GITHUB_LIST_REPOSITORIES_FOR_THE_AUTHENTICATED_USER` - Find target repo if unknown [Prerequisite]
2. `GITHUB_LIST_REPOSITORY_ISSUES` - List existing issues (includes PRs) [Required]
3. `GITHUB_CREATE_AN_ISSUE` - Create a new issue [Required]
4. `GITHUB_CREATE_AN_ISSUE_COMMENT` - Add comments to an issue [Optional]
5. `GITHUB_SEARCH_ISSUES_AND_PULL_REQUESTS` - Search across repos by keyword [Optional]

**Key parameters**:
- `owner`: Repository owner (username or org), case-insensitive
- `repo`: Repository name without .git extension
- `title`: Issue title (required for creation)
- `body`: Issue description (supports Markdown)
- `labels`: Array of label names
- `assignees`: Array of GitHub usernames
- `state`: 'open', 'closed', or 'all' for filtering

**Pitfalls**:
- `GITHUB_LIST_REPOSITORY_ISSUES` returns both issues AND pull requests; check `pull_request` field to distinguish
- Only users with push access can set assignees, labels, and milestones; they are silently dropped otherwise
- Pagination: `per_page` max 100; iterate pages until empty

### 2. Manage Pull Requests

**When to use**: User wants to create, review, or merge pull requests

**Tool sequence**:
1. `GITHUB_FIND_PULL_REQUESTS` - Search and filter PRs [Required]
2. `GITHUB_GET_A_PULL_REQUEST` - Get detailed PR info including mergeable status [Required]
3. `GITHUB_LIST_PULL_REQUESTS_FILES` - Review changed files [Optional]
4. `GITHUB_CREATE_A_PULL_REQUEST` - Create a new PR [Required]
5. `GITHUB_CREATE_AN_ISSUE_COMMENT` - Post review comments [Optional]
6. `GITHUB_LIST_CHECK_RUNS_FOR_A_REF` - Verify CI status before merge [Optional]
7. `GITHUB_MERGE_A_PULL_REQUEST` - Merge after explicit user approval [Required]

**Key parameters**:
- `head`: Source branch with changes (must exist; for cross-repo: 'username:branch')
- `base`: Target branch to merge into (e.g., 'main')
- `title`: PR title (required unless `issue` number provided)
- `merge_method`: 'merge', 'squash', or 'rebase'
- `state`: 'open', 'closed', or 'all'

**Pitfalls**:
- `GITHUB_CREATE_A_PULL_REQUEST` fails with 422 if base/head are invalid, identical, or already merged
- `GITHUB_MERGE_A_PULL_REQUEST` can be rejected if PR is draft, closed, or branch protection applies
- Always verify mergeable status with `GITHUB_GET_A_PULL_REQUEST` immediately before merging
- Require explicit user confirmation before calling MERGE

### 3. Manage Repositories and Branches

**When to use**: User wants to create repos, manage branches, or update repo settings

**Tool sequence**:
1. `GITHUB_LIST_REPOSITORIES_FOR_THE_AUTHENTICATED_USER` - List user's repos [Required]
2. `GITHUB_GET_A_REPOSITORY` - Get detailed repo info [Optional]
3. `GITHUB_CREATE_A_REPOSITORY_FOR_THE_AUTHENTICATED_USER` - Create personal repo [Required]
4. `GITHUB_CREATE_AN_ORGANIZATION_REPOSITORY` - Create org repo [Alternative]
5. `GITHUB_LIST_BRANCHES` - List branches [Required]
6. `GITHUB_CREATE_A_REFERENCE` - Create new branch from SHA [Required]
7. `GITHUB_UPDATE_A_REPOSITORY` - Update repo settings [Optional]

**Key parameters**:
- `name`: Repository name
- `private`: Boolean for visibility
- `ref`: Full reference path (e.g., 'refs/heads/new-branch')
- `sha`: Commit SHA to point the new reference to
- `default_branch`: Default branch name

**Pitfalls**:
- `GITHUB_CREATE_A_REFERENCE` only creates NEW references; use `GITHUB_UPDATE_A_REFERENCE` for existing ones
- `ref` must start with 'refs/' and contain at least two slashes
- `GITHUB_LIST_BRANCHES` paginates via `page`/`per_page`; iterate until empty page
- `GITHUB_DELETE_A_REPOSITORY` is permanent and irreversible; requires admin privileges

### 4. Search Code and Commits

**When to use**: User wants to find code, files, or commits across repositories

**Tool sequence**:
1. `GITHUB_SEARCH_CODE` - Search file contents and paths [Required]
2. `GITHUB_SEARCH_CODE_ALL_PAGES` - Multi-page code search [Alternative]
3.
