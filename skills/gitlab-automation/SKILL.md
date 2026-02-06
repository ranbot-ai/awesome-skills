---
name: gitlab-automation
description: Automate GitLab project management, issues, merge requests, pipelines, branches, and user operations via Rube MCP (Composio). Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [api, git, yaml, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/gitlab-automation
---


# GitLab Automation via Rube MCP

Automate GitLab operations including project management, issue tracking, merge request workflows, CI/CD pipeline monitoring, branch management, and user administration through Composio's GitLab toolkit.

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active GitLab connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `gitlab`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `gitlab`
3. If connection is not ACTIVE, follow the returned auth link to complete GitLab OAuth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Manage Issues

**When to use**: User wants to create, update, list, or search issues in a GitLab project

**Tool sequence**:
1. `GITLAB_GET_PROJECTS` - Find the target project and get its ID [Prerequisite]
2. `GITLAB_LIST_PROJECT_ISSUES` - List and filter issues for a project [Required]
3. `GITLAB_CREATE_PROJECT_ISSUE` - Create a new issue [Required for create]
4. `GITLAB_UPDATE_PROJECT_ISSUE` - Update an existing issue (title, labels, state, assignees) [Required for update]
5. `GITLAB_LIST_PROJECT_USERS` - Find user IDs for assignment [Optional]

**Key parameters**:
- `id`: Project ID (integer) or URL-encoded path (e.g., `"my-group/my-project"`)
- `title`: Issue title (required for creation)
- `description`: Issue body text (max 1,048,576 characters)
- `labels`: Comma-separated label names (e.g., `"bug,critical"`)
- `add_labels` / `remove_labels`: Add or remove labels without replacing all
- `state`: Filter by `"all"`, `"opened"`, or `"closed"`
- `state_event`: `"close"` or `"reopen"` to change issue state
- `assignee_ids`: Array of user IDs; use `[0]` to unassign all
- `issue_iid`: Internal issue ID within the project (required for updates)
- `milestone`: Filter by milestone title
- `search`: Search in title and description
- `scope`: `"created_by_me"`, `"assigned_to_me"`, or `"all"`
- `page` / `per_page`: Pagination (default per_page: 20)

**Pitfalls**:
- `id` accepts either integer project ID or URL-encoded path; wrong IDs yield 4xx errors
- `issue_iid` is the project-internal ID (shown as #42), different from the global issue ID
- Labels in `labels` field replace ALL existing labels; use `add_labels`/`remove_labels` for incremental changes
- Setting `assignee_ids` to empty array does NOT unassign; use `[0]` instead
- `updated_at` field requires administrator or project/group owner rights

### 2. Manage Merge Requests

**When to use**: User wants to list, filter, or review merge requests in a project

**Tool sequence**:
1. `GITLAB_GET_PROJECT` - Get project details and verify access [Prerequisite]
2. `GITLAB_GET_PROJECT_MERGE_REQUESTS` - List and filter merge requests [Required]
3. `GITLAB_GET_REPOSITORY_BRANCHES` - Verify source/target branches [Optional]
4. `GITLAB_LIST_ALL_PROJECT_MEMBERS` - Find reviewers/assignees [Optional]

**Key parameters**:
- `id`: Project ID or URL-encoded path
- `state`: `"opened"`, `"closed"`, `"locked"`, `"merged"`, or `"all"`
- `scope`: `"created_by_me"` (default), `"assigned_to_me"`, or `"all"`
- `source_branch` / `target_branch`: Filter by branch names
- `author_id` / `author_username`: Filter by MR author
- `assignee_id`: Filter by assignee (use `None` for unassigned, `Any` for assigned)
- `reviewer_id` / `reviewer_username`: Filter by reviewer
- `labels`: Comma-separated label filter
- `search`: Search in title and description
- `wip`: `"yes"` for draft MRs, `"no"` for non-draft
- `order_by`: `"created_at"` (default), `"title"`, `"merged_at"`, `"updated_at"`
- `view`: `"simple"` for minimal fields
- `iids[]`: Filter by specific MR internal IDs

**Pitfalls**:
- Default `scope` is `"created_by_me"` which limits results; use `"all"` for complete listings
- `author_id` and `author_username` are mutually exclusive
- `reviewer_id` and `reviewer_username` are mutually exclusive
- `approved` filter requires the `mr_approved_filter` feature flag (disabled by default)
- Large MR histories can be noisy; use filters and moderate `per_page` values

### 3. Manage Projects and Repositories

**When to use**: User wants to list projects, create new projects, or manage branches

**Tool sequence**:
1. `GITLAB_GET_PROJECTS` - List all accessible projects with filters [Required]
2. `GITLAB_GET_PROJECT` - Get detailed info for a specific project [Optional]
3. `GITLAB_LIST_USER_PROJECTS` - List projects owned by a specific user [Optional]
4. `GITLAB_CREATE_PROJECT` - Create a new project [Required for create]
5. `GITLAB_GET_REPOSITORY_BRANCHES` - List branches in a project [Required for branch ops]
6. `GITLAB_CREATE_REPOSITORY_BRANCH` - Create a new branch [Optional]
