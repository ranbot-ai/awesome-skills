---
name: bitbucket-automation
description: Automate Bitbucket repositories, pull requests, branches, issues, and workspace management via Rube MCP (Composio). Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [api, markdown, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/bitbucket-automation
---


# Bitbucket Automation via Rube MCP

Automate Bitbucket operations including repository management, pull request workflows, branch operations, issue tracking, and workspace administration through Composio's Bitbucket toolkit.

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Bitbucket connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `bitbucket`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `bitbucket`
3. If connection is not ACTIVE, follow the returned auth link to complete Bitbucket OAuth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Manage Pull Requests

**When to use**: User wants to create, review, or inspect pull requests

**Tool sequence**:
1. `BITBUCKET_LIST_WORKSPACES` - Discover accessible workspaces [Prerequisite]
2. `BITBUCKET_LIST_REPOSITORIES_IN_WORKSPACE` - Find the target repository [Prerequisite]
3. `BITBUCKET_LIST_BRANCHES` - Verify source and destination branches exist [Prerequisite]
4. `BITBUCKET_CREATE_PULL_REQUEST` - Create a new PR with title, source branch, and optional reviewers [Required]
5. `BITBUCKET_LIST_PULL_REQUESTS` - List PRs filtered by state (OPEN, MERGED, DECLINED) [Optional]
6. `BITBUCKET_GET_PULL_REQUEST` - Get full details of a specific PR by ID [Optional]
7. `BITBUCKET_GET_PULL_REQUEST_DIFF` - Fetch unified diff for code review [Optional]
8. `BITBUCKET_GET_PULL_REQUEST_DIFFSTAT` - Get changed files with lines added/removed [Optional]

**Key parameters**:
- `workspace`: Workspace slug or UUID (required for all operations)
- `repo_slug`: URL-friendly repository name
- `source_branch`: Branch with changes to merge
- `destination_branch`: Target branch (defaults to repo main branch if omitted)
- `reviewers`: List of objects with `uuid` field for reviewer assignment
- `state`: Filter for LIST_PULL_REQUESTS - `OPEN`, `MERGED`, or `DECLINED`
- `max_chars`: Truncation limit for GET_PULL_REQUEST_DIFF to handle large diffs

**Pitfalls**:
- `reviewers` expects an array of objects with `uuid` key, NOT usernames: `[{"uuid": "{...}"}]`
- UUID format must include curly braces: `{123e4567-e89b-12d3-a456-426614174000}`
- `destination_branch` defaults to the repo's main branch if omitted, which may not be `main`
- `pull_request_id` is an integer for GET/DIFF operations but comes back as part of PR listing
- Large diffs can overwhelm context; always set `max_chars` (e.g., 50000) on GET_PULL_REQUEST_DIFF

### 2. Manage Repositories and Workspaces

**When to use**: User wants to list, create, or delete repositories or explore workspaces

**Tool sequence**:
1. `BITBUCKET_LIST_WORKSPACES` - List all accessible workspaces [Required]
2. `BITBUCKET_LIST_REPOSITORIES_IN_WORKSPACE` - List repos with optional BBQL filtering [Required]
3. `BITBUCKET_CREATE_REPOSITORY` - Create a new repo with language, privacy, and project settings [Optional]
4. `BITBUCKET_DELETE_REPOSITORY` - Permanently delete a repository (irreversible) [Optional]
5. `BITBUCKET_LIST_WORKSPACE_MEMBERS` - List members for reviewer assignment or access checks [Optional]

**Key parameters**:
- `workspace`: Workspace slug (find via LIST_WORKSPACES)
- `repo_slug`: URL-friendly name for create/delete
- `q`: BBQL query filter (e.g., `name~"api"`, `project.key="PROJ"`, `is_private=true`)
- `role`: Filter repos by user role: `member`, `contributor`, `admin`, `owner`
- `sort`: Sort field with optional `-` prefix for descending (e.g., `-updated_on`)
- `is_private`: Boolean for repository visibility (defaults to `true`)
- `project_key`: Bitbucket project key; omit to use workspace's oldest project

**Pitfalls**:
- `BITBUCKET_DELETE_REPOSITORY` is **irreversible** and does not affect forks
- BBQL string values MUST be enclosed in double quotes: `name~"my-repo"` not `name~my-repo`
- `repository` is NOT a valid BBQL field; use `name` instead
- Default pagination is 10 results; set `pagelen` explicitly for complete listings
- `CREATE_REPOSITORY` defaults to private; set `is_private: false` for public repos

### 3. Manage Issues

**When to use**: User wants to create, update, list, or comment on repository issues

**Tool sequence**:
1. `BITBUCKET_LIST_ISSUES` - List issues with optional filters for state, priority, kind, assignee [Required]
2. `BITBUCKET_CREATE_ISSUE` - Create a new issue with title, content, priority, and kind [Required]
3. `BITBUCKET_UPDATE_ISSUE` - Modify issue attributes (state, priority, assignee, etc.) [Optional]
4. `BITBUCKET_CREATE_ISSUE_COMMENT` - Add a markdown comment to an existing issue [Optional]
5. `BITBUCKET_DELETE_ISSUE` - Permanently delete an issue [Optional]

**Key parameters**:
- `issue_id`: String identifier for th
