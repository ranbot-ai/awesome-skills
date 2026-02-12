---
name: basecamp-automation
description: Automate Basecamp project management, to-dos, messages, people, and to-do list organization via Rube MCP (Composio). Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [html, api, markdown, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/basecamp-automation
---


# Basecamp Automation via Rube MCP

Automate Basecamp operations including project management, to-do list creation, task management, message board posting, people management, and to-do group organization through Composio's Basecamp toolkit.

**Toolkit docs**: [composio.dev/toolkits/basecamp](https://composio.dev/toolkits/basecamp)

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Basecamp connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `basecamp`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `basecamp`
3. If connection is not ACTIVE, follow the returned auth link to complete Basecamp OAuth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Manage To-Do Lists and Tasks

**When to use**: User wants to create to-do lists, add tasks, or organize work within a Basecamp project

**Tool sequence**:
1. `BASECAMP_GET_PROJECTS` - List projects to find the target bucket_id [Prerequisite]
2. `BASECAMP_GET_BUCKETS_TODOSETS` - Get the to-do set within a project [Prerequisite]
3. `BASECAMP_GET_BUCKETS_TODOSETS_TODOLISTS` - List existing to-do lists to avoid duplicates [Optional]
4. `BASECAMP_POST_BUCKETS_TODOSETS_TODOLISTS` - Create a new to-do list in a to-do set [Required for list creation]
5. `BASECAMP_GET_BUCKETS_TODOLISTS` - Get details of a specific to-do list [Optional]
6. `BASECAMP_POST_BUCKETS_TODOLISTS_TODOS` - Create a to-do item in a to-do list [Required for task creation]
7. `BASECAMP_CREATE_TODO` - Alternative tool for creating individual to-dos [Alternative]
8. `BASECAMP_GET_BUCKETS_TODOLISTS_TODOS` - List to-dos within a to-do list [Optional]

**Key parameters for creating to-do lists**:
- `bucket_id`: Integer project/bucket ID (from GET_PROJECTS)
- `todoset_id`: Integer to-do set ID (from GET_BUCKETS_TODOSETS)
- `name`: Title of the to-do list (required)
- `description`: HTML-formatted description (supports Rich text)

**Key parameters for creating to-dos**:
- `bucket_id`: Integer project/bucket ID
- `todolist_id`: Integer to-do list ID
- `content`: What the to-do is for (required)
- `description`: HTML details about the to-do
- `assignee_ids`: Array of integer person IDs
- `due_on`: Due date in `YYYY-MM-DD` format
- `starts_on`: Start date in `YYYY-MM-DD` format
- `notify`: Boolean to notify assignees (defaults to false)
- `completion_subscriber_ids`: Person IDs notified upon completion

**Pitfalls**:
- A project (bucket) can contain multiple to-do sets; selecting the wrong `todoset_id` creates lists in the wrong section
- Always check existing to-do lists before creating to avoid near-duplicate names
- Success payloads include user-facing URLs (`app_url`, `app_todos_url`); prefer returning these over raw IDs
- All IDs (`bucket_id`, `todoset_id`, `todolist_id`) are integers, not strings
- Descriptions support HTML formatting only, not Markdown

### 2. Post and Manage Messages

**When to use**: User wants to post messages to a project message board or update existing messages

**Tool sequence**:
1. `BASECAMP_GET_PROJECTS` - Find the target project and bucket_id [Prerequisite]
2. `BASECAMP_GET_MESSAGE_BOARD` - Get the message board ID for the project [Prerequisite]
3. `BASECAMP_CREATE_MESSAGE` - Create a new message on the board [Required]
4. `BASECAMP_POST_BUCKETS_MESSAGE_BOARDS_MESSAGES` - Alternative message creation tool [Fallback]
5. `BASECAMP_GET_MESSAGE` - Read a specific message by ID [Optional]
6. `BASECAMP_PUT_BUCKETS_MESSAGES` - Update an existing message [Optional]

**Key parameters**:
- `bucket_id`: Integer project/bucket ID
- `message_board_id`: Integer message board ID (from GET_MESSAGE_BOARD)
- `subject`: Message title (required)
- `content`: HTML body of the message
- `status`: Set to `"active"` to publish immediately
- `category_id`: Message type classification (optional)
- `subscriptions`: Array of person IDs to notify; omit to notify all project members

**Pitfalls**:
- `status="draft"` can produce HTTP 400; use `status="active"` as the reliable option
- `bucket_id` and `message_board_id` must belong to the same project; mismatches fail or misroute
- Message content supports HTML tags only; not Markdown
- Updates via `PUT_BUCKETS_MESSAGES` replace the entire body -- include the full corrected content, not just a diff
- Prefer `app_url` from the response for user-facing confirmation links
- Both `CREATE_MESSAGE` and `POST_BUCKETS_MESSAGE_BOARDS_MESSAGES` do the same thing; use CREATE_MESSAGE first and fall back to POST if it fails

### 3. Manage People and Access

**When to use**: User wants to list people, manage project access, or add new users

**Tool sequence**:
1. `BASECAMP_GET_PEOPLE` - List 
